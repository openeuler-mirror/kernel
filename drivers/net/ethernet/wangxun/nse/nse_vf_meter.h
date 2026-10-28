/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_VF_METER_H_
#define _NSE_VF_METER_H_

struct nse_pf;

/* TX means ingress acl meter,
 * tx traffic from vf viewed as ingress direction from switch
 */
enum {
	NSE_VF_RATE_LIMIT_RX,
	NSE_VF_RATE_LIMIT_TX,
};

enum nse_vf_meter_mode {
	NSE_VF_RATE_LIMIT_BPS,
	NSE_VF_RATE_LIMIT_PPS,
	NSE_VF_RATE_LIMIT_MAX,
};

struct nse_vf_meter_xps {
	u64 rate;
	u64 burst;
	u64 packets_dropped;
	u64 bytes_dropped;
	struct nse_acl_fltr_info *fltr_info;
};

struct nse_vf_meter {
	struct mutex vf_meter_lock;
	bool is_meter_en;
	struct nse_vf_meter_xps *meter_xps[NSE_VF_RATE_LIMIT_MAX];
};

int
nse_vf_meter_create_meters(struct nse_pf *pf);

void
nse_vf_meter_destroy_all(struct nse_pf *pf);

int
nse_set_vf_meter_data(struct nse_pf *pf,
		u16 vf_id, int data_type, int rx_tx, int xps, u64 data);

int
nse_get_vf_meter_data(struct nse_pf *pf,
		u16 vf_id, int data_type, int rx_tx, int xps, u64 *data);

#endif
