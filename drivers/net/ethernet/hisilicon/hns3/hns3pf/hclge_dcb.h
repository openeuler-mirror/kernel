/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2016-2017 Hisilicon Limited.

#ifndef __HCLGE_DCB_H__
#define __HCLGE_DCB_H__

#include "hclge_main.h"

struct hclge_mbx_tc_info;

#ifdef CONFIG_HNS3_DCB
void hclge_dcb_ops_set(struct hclge_dev *hdev);
int hclge_mbx_set_vf_multi_tc(struct hclge_vport *vport,
			      struct hclge_mbx_tc_info *tc_info);
#else
static inline void hclge_dcb_ops_set(struct hclge_dev *hdev) {}
static inline int hclge_mbx_set_vf_multi_tc(struct hclge_vport *vport,
					    struct hclge_mbx_tc_info *tc_info)
{
	return -EOPNOTSUPP;
}

#endif

#define HCLGE_BYTE_BITS		8ULL
#define HCLGE_RATE_UNIT_MBPS	1000000ULL /* 1Mbps */

#endif /* __HCLGE_DCB_H__ */
