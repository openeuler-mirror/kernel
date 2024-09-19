/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei HNS3_UDMA Linux driver
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

#ifndef _HNS3_UDMA_SYSFS_H
#define _HNS3_UDMA_SYSFS_H

#include <linux/device.h>
#include "hns3_udma_device.h"

#define HNS3_UDMA_DCQCN_AI_OFS 0
#define HNS3_UDMA_DCQCN_AI_SZ sizeof(u16)
#define HNS3_UDMA_DCQCN_AI_MAX ((u16) (~0U))
#define HNS3_UDMA_DCQCN_F_OFS (HNS3_UDMA_DCQCN_AI_OFS + HNS3_UDMA_DCQCN_AI_SZ)
#define HNS3_UDMA_DCQCN_F_SZ sizeof(u8)
#define HNS3_UDMA_DCQCN_F_MAX ((u8) (~0U))
#define HNS3_UDMA_DCQCN_TKP_OFS (HNS3_UDMA_DCQCN_F_OFS + HNS3_UDMA_DCQCN_F_SZ)
#define HNS3_UDMA_DCQCN_TKP_SZ sizeof(u8)
#define HNS3_UDMA_DCQCN_TKP_MAX 15
#define HNS3_UDMA_DCQCN_TMP_OFS (HNS3_UDMA_DCQCN_TKP_OFS + HNS3_UDMA_DCQCN_TKP_SZ)
#define HNS3_UDMA_DCQCN_TMP_SZ sizeof(u16)
#define HNS3_UDMA_DCQCN_TMP_MAX 15
#define HNS3_UDMA_DCQCN_ALP_OFS (HNS3_UDMA_DCQCN_TMP_OFS + HNS3_UDMA_DCQCN_TMP_SZ)
#define HNS3_UDMA_DCQCN_ALP_SZ sizeof(u16)
#define HNS3_UDMA_DCQCN_ALP_MAX ((u16) (~0U))
#define HNS3_UDMA_DCQCN_MAX_SPEED_OFS (HNS3_UDMA_DCQCN_ALP_OFS + \
					HNS3_UDMA_DCQCN_ALP_SZ)
#define HNS3_UDMA_DCQCN_MAX_SPEED_SZ sizeof(u32)
#define HNS3_UDMA_DCQCN_MAX_SPEED_MAX ((u32) (~0U))
#define HNS3_UDMA_DCQCN_G_OFS (HNS3_UDMA_DCQCN_MAX_SPEED_OFS + \
					HNS3_UDMA_DCQCN_MAX_SPEED_SZ)
#define HNS3_UDMA_DCQCN_G_SZ sizeof(u8)
#define HNS3_UDMA_DCQCN_G_MAX 15
#define HNS3_UDMA_DCQCN_AL_OFS (HNS3_UDMA_DCQCN_G_OFS + HNS3_UDMA_DCQCN_G_SZ)
#define HNS3_UDMA_DCQCN_AL_SZ sizeof(u8)
#define HNS3_UDMA_DCQCN_AL_MAX ((u8) (~0U))
#define HNS3_UDMA_DCQCN_CNP_TIME_OFS (HNS3_UDMA_DCQCN_AL_OFS + \
					HNS3_UDMA_DCQCN_AL_SZ)
#define HNS3_UDMA_DCQCN_CNP_TIME_SZ sizeof(u8)
#define HNS3_UDMA_DCQCN_CNP_TIME_MAX ((u8) (~0U))
#define HNS3_UDMA_DCQCN_ASHIFT_OFS (HNS3_UDMA_DCQCN_CNP_TIME_OFS + \
					HNS3_UDMA_DCQCN_CNP_TIME_SZ)
#define HNS3_UDMA_DCQCN_ASHIFT_SZ sizeof(u8)
#define HNS3_UDMA_DCQCN_ASHIFT_MAX 15
#define HNS3_UDMA_DCQCN_LIFESPAN_OFS (HNS3_UDMA_DCQCN_ASHIFT_OFS + \
				      HNS3_UDMA_DCQCN_ASHIFT_SZ)
#define HNS3_UDMA_DCQCN_LIFESPAN_SZ sizeof(u32)
#define HNS3_UDMA_DCQCN_LIFESPAN_MAX 1000

#define HNS3_UDMA_LDCP_CWD0_OFS 0
#define HNS3_UDMA_LDCP_CWD0_SZ sizeof(u32)
#define HNS3_UDMA_LDCP_CWD0_MAX ((u32) (~0U))
#define HNS3_UDMA_LDCP_ALPHA_OFS (HNS3_UDMA_LDCP_CWD0_OFS + HNS3_UDMA_LDCP_CWD0_SZ)
#define HNS3_UDMA_LDCP_ALPHA_SZ sizeof(u8)
#define HNS3_UDMA_LDCP_ALPHA_MAX ((u8) (~0U))
#define HNS3_UDMA_LDCP_GAMMA_OFS (HNS3_UDMA_LDCP_ALPHA_OFS + \
				  HNS3_UDMA_LDCP_ALPHA_SZ)
#define HNS3_UDMA_LDCP_GAMMA_SZ sizeof(u8)
#define HNS3_UDMA_LDCP_GAMMA_MAX ((u8) (~0U))
#define HNS3_UDMA_LDCP_BETA_OFS (HNS3_UDMA_LDCP_GAMMA_OFS + \
				 HNS3_UDMA_LDCP_GAMMA_SZ)
#define HNS3_UDMA_LDCP_BETA_SZ sizeof(u8)
#define HNS3_UDMA_LDCP_BETA_MAX ((u8) (~0U))
#define HNS3_UDMA_LDCP_ETA_OFS (HNS3_UDMA_LDCP_BETA_OFS + HNS3_UDMA_LDCP_BETA_SZ)
#define HNS3_UDMA_LDCP_ETA_SZ sizeof(u8)
#define HNS3_UDMA_LDCP_ETA_MAX ((u8) (~0U))
#define HNS3_UDMA_LDCP_LIFESPAN_OFS (4 * sizeof(u32))
#define HNS3_UDMA_LDCP_LIFESPAN_SZ sizeof(u32)
#define HNS3_UDMA_LDCP_LIFESPAN_MAX 1000

#define HNS3_UDMA_HC3_INITIAL_WINDOW_OFS 0
#define HNS3_UDMA_HC3_INITIAL_WINDOW_SZ sizeof(u32)
#define HNS3_UDMA_HC3_INITIAL_WINDOW_MAX ((u32) (~0U))
#define HNS3_UDMA_HC3_BANDWIDTH_OFS (HNS3_UDMA_HC3_INITIAL_WINDOW_OFS + \
				     HNS3_UDMA_HC3_INITIAL_WINDOW_SZ)
#define HNS3_UDMA_HC3_BANDWIDTH_SZ sizeof(u32)
#define HNS3_UDMA_HC3_BANDWIDTH_MAX ((u32) (~0U))
#define HNS3_UDMA_HC3_QLEN_SHIFT_OFS (HNS3_UDMA_HC3_BANDWIDTH_OFS + \
				      HNS3_UDMA_HC3_BANDWIDTH_SZ)
#define HNS3_UDMA_HC3_QLEN_SHIFT_SZ sizeof(u8)
#define HNS3_UDMA_HC3_QLEN_SHIFT_MAX ((u8) (~0U))
#define HNS3_UDMA_HC3_PORT_USAGE_SHIFT_OFS (HNS3_UDMA_HC3_QLEN_SHIFT_OFS + \
					    HNS3_UDMA_HC3_QLEN_SHIFT_SZ)
#define HNS3_UDMA_HC3_PORT_USAGE_SHIFT_SZ sizeof(u8)
#define HNS3_UDMA_HC3_PORT_USAGE_SHIFT_MAX ((u8) (~0U))
#define HNS3_UDMA_HC3_OVER_PERIOD_OFS (HNS3_UDMA_HC3_PORT_USAGE_SHIFT_OFS + \
				       HNS3_UDMA_HC3_PORT_USAGE_SHIFT_SZ)
#define HNS3_UDMA_HC3_OVER_PERIOD_SZ sizeof(u8)
#define HNS3_UDMA_HC3_OVER_PERIOD_MAX ((u8) (~0U))
#define HNS3_UDMA_HC3_MAX_STAGE_OFS (HNS3_UDMA_HC3_OVER_PERIOD_OFS + \
					HNS3_UDMA_HC3_OVER_PERIOD_SZ)
#define HNS3_UDMA_HC3_MAX_STAGE_SZ sizeof(u8)
#define HNS3_UDMA_HC3_MAX_STAGE_MAX ((u8) (~0U))
#define HNS3_UDMA_HC3_GAMMA_SHIFT_OFS (HNS3_UDMA_HC3_MAX_STAGE_OFS + \
				       HNS3_UDMA_HC3_MAX_STAGE_SZ)
#define HNS3_UDMA_HC3_GAMMA_SHIFT_SZ sizeof(u8)
#define HNS3_UDMA_HC3_GAMMA_SHIFT_MAX 15
#define HNS3_UDMA_HC3_LIFESPAN_OFS (4 * sizeof(u32))
#define HNS3_UDMA_HC3_LIFESPAN_SZ sizeof(u32)
#define HNS3_UDMA_HC3_LIFESPAN_MAX 1000

#define HNS3_UDMA_DIP_AI_OFS 0
#define HNS3_UDMA_DIP_AI_SZ sizeof(u16)
#define HNS3_UDMA_DIP_AI_MAX ((u16) (~0U))
#define HNS3_UDMA_DIP_F_OFS (HNS3_UDMA_DIP_AI_OFS + HNS3_UDMA_DIP_AI_SZ)
#define HNS3_UDMA_DIP_F_SZ sizeof(u8)
#define HNS3_UDMA_DIP_F_MAX ((u8) (~0U))
#define HNS3_UDMA_DIP_TKP_OFS (HNS3_UDMA_DIP_F_OFS + HNS3_UDMA_DIP_F_SZ)
#define HNS3_UDMA_DIP_TKP_SZ sizeof(u8)
#define HNS3_UDMA_DIP_TKP_MAX 15
#define HNS3_UDMA_DIP_TMP_OFS (HNS3_UDMA_DIP_TKP_OFS + HNS3_UDMA_DIP_TKP_SZ)
#define HNS3_UDMA_DIP_TMP_SZ sizeof(u16)
#define HNS3_UDMA_DIP_TMP_MAX 15
#define HNS3_UDMA_DIP_ALP_OFS (HNS3_UDMA_DIP_TMP_OFS + HNS3_UDMA_DIP_TMP_SZ)
#define HNS3_UDMA_DIP_ALP_SZ sizeof(u16)
#define HNS3_UDMA_DIP_ALP_MAX ((u16) (~0U))
#define HNS3_UDMA_DIP_MAX_SPEED_OFS (HNS3_UDMA_DIP_ALP_OFS + HNS3_UDMA_DIP_ALP_SZ)
#define HNS3_UDMA_DIP_MAX_SPEED_SZ sizeof(u32)
#define HNS3_UDMA_DIP_MAX_SPEED_MAX ((u32) (~0U))
#define HNS3_UDMA_DIP_G_OFS (HNS3_UDMA_DIP_MAX_SPEED_OFS + \
				HNS3_UDMA_DIP_MAX_SPEED_SZ)
#define HNS3_UDMA_DIP_G_SZ sizeof(u8)
#define HNS3_UDMA_DIP_G_MAX 15
#define HNS3_UDMA_DIP_AL_OFS (HNS3_UDMA_DIP_G_OFS + HNS3_UDMA_DIP_G_SZ)
#define HNS3_UDMA_DIP_AL_SZ sizeof(u8)
#define HNS3_UDMA_DIP_AL_MAX ((u8) (~0U))
#define HNS3_UDMA_DIP_CNP_TIME_OFS (HNS3_UDMA_DIP_AL_OFS + HNS3_UDMA_DIP_AL_SZ)
#define HNS3_UDMA_DIP_CNP_TIME_SZ sizeof(u8)
#define HNS3_UDMA_DIP_CNP_TIME_MAX ((u8) (~0U))
#define HNS3_UDMA_DIP_ASHIFT_OFS (HNS3_UDMA_DIP_CNP_TIME_OFS + \
					HNS3_UDMA_DIP_CNP_TIME_SZ)
#define HNS3_UDMA_DIP_ASHIFT_SZ sizeof(u8)
#define HNS3_UDMA_DIP_ASHIFT_MAX 15
#define HNS3_UDMA_DIP_LIFESPAN_OFS (HNS3_UDMA_DIP_ASHIFT_OFS + \
					HNS3_UDMA_DIP_ASHIFT_SZ)
#define HNS3_UDMA_DIP_LIFESPAN_SZ sizeof(u32)
#define HNS3_UDMA_DIP_LIFESPAN_MAX 1000

#define ATTR_RW_RONLY_RONLY 0644

#define HNS3_UDMA_NUM_QP_MAX		524288
#define HNS3_UDMA_NUM_QP_MIN		8

#define HNS3_UDMA_CNP_ATTR_SEL_MAX	1
#define HNS3_UDMA_CNP_DSCP_MAX	63

struct hns3_udma_num_qp_cmd {
	uint32_t num;
};

struct hns3_udma_port_attribute {
	struct attribute attr;
	ssize_t (*show)(struct hns3_udma_port *pdata,
			struct hns3_udma_port_attribute *attr, char *buf);
	ssize_t (*store)(struct hns3_udma_port *pdata,
			 struct hns3_udma_port_attribute *attr, const char *buf,
			 size_t count);
};

struct hns3_udma_port_cc_attr {
	struct hns3_udma_port_attribute	port_attr;
	enum hns3_udma_cong_type	algo_type;
	uint32_t			offset;
	uint32_t			size;
	uint32_t			min;
	uint32_t			max;
};

enum hns3_udma_cnp_param_type {
	CNP_PARAM_ATTR_SEL,
	CNP_PARAM_DSCP,
};

struct hns3_udma_cnp_attr {
	struct hns3_udma_port_attribute port_attr;
	enum hns3_udma_cnp_param_type type;
};

static inline struct hns3_udma_cnp_attr *to_hns3_udma_cnp_attr(
						struct hns3_udma_port_attribute *attr)
{
	return container_of(attr, struct hns3_udma_cnp_attr, port_attr);
}

int hns3_udma_register_cc_sysfs(struct hns3_udma_dev *udma_dev);
void hns3_udma_unregister_cc_sysfs(struct hns3_udma_dev *udma_dev);

int hns3_udma_register_num_qp_sysfs(struct hns3_udma_dev *udma_dev);
void hns3_udma_unregister_num_qp_sysfs(struct hns3_udma_dev *udma_dev);

#endif /* _HNS3_UDMA_SYSFS_H */
