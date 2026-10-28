/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_REPR_METER_H_
#define _NSE_REPR_METER_H_

struct nse_rep_meter {
	u64 rate;
	u64 burst;
	u64 packets_dropped;
	u64 bytes_dropped;
	struct nse_acl_fltr_info *fltr_info;
};

int nse_rep_set_miss_meter(struct nse_pf *pf, bool  is_uplink,
			   struct nse_repr *repr, u64 rate, u64 burst);
int nse_rep_get_miss_meter_data(struct nse_pf *pf, bool  is_uplink, struct nse_repr *repr,
			   int data_type, u64 *data);
void nse_acl_destrory_hw_repr_meter(struct nse_vsi *vsi, struct nse_rep_meter *meter);

#endif
