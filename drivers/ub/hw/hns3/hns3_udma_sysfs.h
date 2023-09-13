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

#ifndef _UDMA_SYSFS_H
#define _UDMA_SYSFS_H

#include <linux/device.h>
#include "hns3_udma_device.h"

#define UDMA_DCQCN_AI_OFS 0
#define UDMA_DCQCN_AI_SZ sizeof(u16)
#define UDMA_DCQCN_AI_MAX ((u16) (~0U))
#define UDMA_DCQCN_F_OFS (UDMA_DCQCN_AI_OFS + UDMA_DCQCN_AI_SZ)
#define UDMA_DCQCN_F_SZ sizeof(u8)
#define UDMA_DCQCN_F_MAX ((u8) (~0U))
#define UDMA_DCQCN_TKP_OFS (UDMA_DCQCN_F_OFS + UDMA_DCQCN_F_SZ)
#define UDMA_DCQCN_TKP_SZ sizeof(u8)
#define UDMA_DCQCN_TKP_MAX 15
#define UDMA_DCQCN_TMP_OFS (UDMA_DCQCN_TKP_OFS + UDMA_DCQCN_TKP_SZ)
#define UDMA_DCQCN_TMP_SZ sizeof(u16)
#define UDMA_DCQCN_TMP_MAX 15
#define UDMA_DCQCN_ALP_OFS (UDMA_DCQCN_TMP_OFS + UDMA_DCQCN_TMP_SZ)
#define UDMA_DCQCN_ALP_SZ sizeof(u16)
#define UDMA_DCQCN_ALP_MAX ((u16) (~0U))
#define UDMA_DCQCN_MAX_SPEED_OFS (UDMA_DCQCN_ALP_OFS + \
					UDMA_DCQCN_ALP_SZ)
#define UDMA_DCQCN_MAX_SPEED_SZ sizeof(u32)
#define UDMA_DCQCN_MAX_SPEED_MAX ((u32) (~0U))
#define UDMA_DCQCN_G_OFS (UDMA_DCQCN_MAX_SPEED_OFS + \
					UDMA_DCQCN_MAX_SPEED_SZ)
#define UDMA_DCQCN_G_SZ sizeof(u8)
#define UDMA_DCQCN_G_MAX 15
#define UDMA_DCQCN_AL_OFS (UDMA_DCQCN_G_OFS + UDMA_DCQCN_G_SZ)
#define UDMA_DCQCN_AL_SZ sizeof(u8)
#define UDMA_DCQCN_AL_MAX ((u8) (~0U))
#define UDMA_DCQCN_CNP_TIME_OFS (UDMA_DCQCN_AL_OFS + \
					UDMA_DCQCN_AL_SZ)
#define UDMA_DCQCN_CNP_TIME_SZ sizeof(u8)
#define UDMA_DCQCN_CNP_TIME_MAX ((u8) (~0U))
#define UDMA_DCQCN_ASHIFT_OFS (UDMA_DCQCN_CNP_TIME_OFS + \
					UDMA_DCQCN_CNP_TIME_SZ)
#define UDMA_DCQCN_ASHIFT_SZ sizeof(u8)
#define UDMA_DCQCN_ASHIFT_MAX 15
#define UDMA_DCQCN_LIFESPAN_OFS (UDMA_DCQCN_ASHIFT_OFS + \
					UDMA_DCQCN_ASHIFT_SZ)
#define UDMA_DCQCN_LIFESPAN_SZ sizeof(u32)
#define UDMA_DCQCN_LIFESPAN_MAX 1000

#define UDMA_LDCP_CWD0_OFS 0
#define UDMA_LDCP_CWD0_SZ sizeof(u32)
#define UDMA_LDCP_CWD0_MAX ((u32) (~0U))
#define UDMA_LDCP_ALPHA_OFS (UDMA_LDCP_CWD0_OFS + UDMA_LDCP_CWD0_SZ)
#define UDMA_LDCP_ALPHA_SZ sizeof(u8)
#define UDMA_LDCP_ALPHA_MAX ((u8) (~0U))
#define UDMA_LDCP_GAMMA_OFS (UDMA_LDCP_ALPHA_OFS + \
					UDMA_LDCP_ALPHA_SZ)
#define UDMA_LDCP_GAMMA_SZ sizeof(u8)
#define UDMA_LDCP_GAMMA_MAX ((u8) (~0U))
#define UDMA_LDCP_BETA_OFS (UDMA_LDCP_GAMMA_OFS + \
					UDMA_LDCP_GAMMA_SZ)
#define UDMA_LDCP_BETA_SZ sizeof(u8)
#define UDMA_LDCP_BETA_MAX ((u8) (~0U))
#define UDMA_LDCP_ETA_OFS (UDMA_LDCP_BETA_OFS + UDMA_LDCP_BETA_SZ)
#define UDMA_LDCP_ETA_SZ sizeof(u8)
#define UDMA_LDCP_ETA_MAX ((u8) (~0U))
#define UDMA_LDCP_LIFESPAN_OFS (4 * sizeof(u32))
#define UDMA_LDCP_LIFESPAN_SZ sizeof(u32)
#define UDMA_LDCP_LIFESPAN_MAX 1000

#define UDMA_HC3_INITIAL_WINDOW_OFS 0
#define UDMA_HC3_INITIAL_WINDOW_SZ sizeof(u32)
#define UDMA_HC3_INITIAL_WINDOW_MAX ((u32) (~0U))
#define UDMA_HC3_BANDWIDTH_OFS (UDMA_HC3_INITIAL_WINDOW_OFS + \
					UDMA_HC3_INITIAL_WINDOW_SZ)
#define UDMA_HC3_BANDWIDTH_SZ sizeof(u32)
#define UDMA_HC3_BANDWIDTH_MAX ((u32) (~0U))
#define UDMA_HC3_QLEN_SHIFT_OFS (UDMA_HC3_BANDWIDTH_OFS + \
					UDMA_HC3_BANDWIDTH_SZ)
#define UDMA_HC3_QLEN_SHIFT_SZ sizeof(u8)
#define UDMA_HC3_QLEN_SHIFT_MAX ((u8) (~0U))
#define UDMA_HC3_PORT_USAGE_SHIFT_OFS (UDMA_HC3_QLEN_SHIFT_OFS + \
						UDMA_HC3_QLEN_SHIFT_SZ)
#define UDMA_HC3_PORT_USAGE_SHIFT_SZ sizeof(u8)
#define UDMA_HC3_PORT_USAGE_SHIFT_MAX ((u8) (~0U))
#define UDMA_HC3_OVER_PERIOD_OFS (UDMA_HC3_PORT_USAGE_SHIFT_OFS + \
					UDMA_HC3_PORT_USAGE_SHIFT_SZ)
#define UDMA_HC3_OVER_PERIOD_SZ sizeof(u8)
#define UDMA_HC3_OVER_PERIOD_MAX ((u8) (~0U))
#define UDMA_HC3_MAX_STAGE_OFS (UDMA_HC3_OVER_PERIOD_OFS + \
					UDMA_HC3_OVER_PERIOD_SZ)
#define UDMA_HC3_MAX_STAGE_SZ sizeof(u8)
#define UDMA_HC3_MAX_STAGE_MAX ((u8) (~0U))
#define UDMA_HC3_GAMMA_SHIFT_OFS (UDMA_HC3_MAX_STAGE_OFS + \
					UDMA_HC3_MAX_STAGE_SZ)
#define UDMA_HC3_GAMMA_SHIFT_SZ sizeof(u8)
#define UDMA_HC3_GAMMA_SHIFT_MAX 15
#define UDMA_HC3_LIFESPAN_OFS (4 * sizeof(u32))
#define UDMA_HC3_LIFESPAN_SZ sizeof(u32)
#define UDMA_HC3_LIFESPAN_MAX 1000

#define UDMA_DIP_AI_OFS 0
#define UDMA_DIP_AI_SZ sizeof(u16)
#define UDMA_DIP_AI_MAX ((u16) (~0U))
#define UDMA_DIP_F_OFS (UDMA_DIP_AI_OFS + UDMA_DIP_AI_SZ)
#define UDMA_DIP_F_SZ sizeof(u8)
#define UDMA_DIP_F_MAX ((u8) (~0U))
#define UDMA_DIP_TKP_OFS (UDMA_DIP_F_OFS + UDMA_DIP_F_SZ)
#define UDMA_DIP_TKP_SZ sizeof(u8)
#define UDMA_DIP_TKP_MAX 15
#define UDMA_DIP_TMP_OFS (UDMA_DIP_TKP_OFS + UDMA_DIP_TKP_SZ)
#define UDMA_DIP_TMP_SZ sizeof(u16)
#define UDMA_DIP_TMP_MAX 15
#define UDMA_DIP_ALP_OFS (UDMA_DIP_TMP_OFS + UDMA_DIP_TMP_SZ)
#define UDMA_DIP_ALP_SZ sizeof(u16)
#define UDMA_DIP_ALP_MAX ((u16) (~0U))
#define UDMA_DIP_MAX_SPEED_OFS (UDMA_DIP_ALP_OFS + UDMA_DIP_ALP_SZ)
#define UDMA_DIP_MAX_SPEED_SZ sizeof(u32)
#define UDMA_DIP_MAX_SPEED_MAX ((u32) (~0U))
#define UDMA_DIP_G_OFS (UDMA_DIP_MAX_SPEED_OFS + \
				UDMA_DIP_MAX_SPEED_SZ)
#define UDMA_DIP_G_SZ sizeof(u8)
#define UDMA_DIP_G_MAX 15
#define UDMA_DIP_AL_OFS (UDMA_DIP_G_OFS + UDMA_DIP_G_SZ)
#define UDMA_DIP_AL_SZ sizeof(u8)
#define UDMA_DIP_AL_MAX ((u8) (~0U))
#define UDMA_DIP_CNP_TIME_OFS (UDMA_DIP_AL_OFS + UDMA_DIP_AL_SZ)
#define UDMA_DIP_CNP_TIME_SZ sizeof(u8)
#define UDMA_DIP_CNP_TIME_MAX ((u8) (~0U))
#define UDMA_DIP_ASHIFT_OFS (UDMA_DIP_CNP_TIME_OFS + \
					UDMA_DIP_CNP_TIME_SZ)
#define UDMA_DIP_ASHIFT_SZ sizeof(u8)
#define UDMA_DIP_ASHIFT_MAX 15
#define UDMA_DIP_LIFESPAN_OFS (UDMA_DIP_ASHIFT_OFS + \
					UDMA_DIP_ASHIFT_SZ)
#define UDMA_DIP_LIFESPAN_SZ sizeof(u32)
#define UDMA_DIP_LIFESPAN_MAX 1000

#define ATTR_RW_RONLY_RONLY 0644

struct udma_port_attribute {
	struct attribute attr;
	ssize_t (*show)(struct udma_port *pdata,
			struct udma_port_attribute *attr, char *buf);
	ssize_t (*store)(struct udma_port *pdata,
			 struct udma_port_attribute *attr, const char *buf,
			 size_t count);
};

struct udma_port_cc_attr {
	struct udma_port_attribute	port_attr;
	enum udma_cong_type		algo_type;
	uint32_t			offset;
	uint32_t			size;
	uint32_t			min;
	uint32_t			max;
};

int udma_register_cc_sysfs(struct udma_dev *udma_dev);
void udma_unregister_cc_sysfs(struct udma_dev *udma_dev);

#endif /* _UDMA_SYSFS_H */
