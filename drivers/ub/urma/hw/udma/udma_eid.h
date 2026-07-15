/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_EID_H__
#define __UDMA_EID_H__

#include <ub/urma/ubcore_types.h>
#include "udma_cmd.h"

struct udma_seid_upi {
	union ubcore_eid seid;
	uint32_t upi;
	uint32_t rsvd0[3];
};

int udma_add_one_eid(struct udma_dev *udma_dev, struct udma_ctrlq_eid_info *eid_info);
int udma_del_one_eid(struct udma_dev *udma_dev, struct udma_ctrlq_eid_info *eid_info);
void udma_del_eid_guid_by_ue_id(struct udma_dev *udma_dev, uint32_t ue_id);
int udma_query_eid_from_ctrl_cpu(struct udma_dev *udma_dev);
int udma_add_one_eid_guid(struct udma_dev *udma_dev,
			  struct udma_ctrlq_ue_eid_guid_out *eid_guid_info);
int udma_del_one_eid_guid(struct udma_dev *udma_dev,
			  struct udma_ctrlq_ue_eid_guid_out *eid_guid_info);

#endif /* __UDMA_EID_H__ */
