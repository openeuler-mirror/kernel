/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_FC_H_
#define _NBL_FC_H_

#include "nbl_resource.h"

#define NBL_COUNTER_PERIOD_INTERVAL msecs_to_jiffies(3000)

#define NBL_FLOW_STAT_CLR_OFT (3)
#define NBL_FLOW_STAT_NUM_MASK (0x7)

#define NBL_CMDQ_ACL_STAT_BASE_LEN 32

struct nbl_stats_data {
	u32 flow_id;
	u64 bytes;
	u64 packets;
};

int nbl_fc_add_stats(void *priv, enum nbl_pp_fc_type fc_type, unsigned long cookie);
int nbl_fc_del_stats(void *priv, unsigned long cookie);
int nbl_fc_setup_ops(struct nbl_resource_ops *res_ops);
void nbl_fc_remove_ops(struct nbl_resource_ops *res_ops);
int nbl_fc_mgt_start(struct nbl_fc_mgt *mgt);
void nbl_fc_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_fc_setup_mgt(struct device *dev, struct nbl_fc_mgt **fc_mgt);
int nbl_fc_set_stats(struct nbl_fc_mgt *mgt, void *data, unsigned long cookie, bool is_spec_id);
int nbl_draco_add_stats(void *priv, bool is_spec, u64 cookie,
			u32 flow_id, u16 bind_car_id);
int nbl_draco_del_stats(void *priv, bool is_spec, u64 cookie);
#endif
